/**
 * A chunk staging area in IndexedDB, for the receiving side.
 *
 * The naive receiver keeps every arriving chunk in an array and calls `new Blob(...)`
 * at the end. That works until it doesn't: a 50 GB file cannot be held in a tab's
 * memory, and on iOS Safari the tab is killed long before that — somewhere in the low
 * hundreds of megabytes, without warning and without a catchable error.
 *
 * So chunks go to disk as they arrive, and memory holds only the one in hand. At the
 * end the browser assembles the Blob from the stored chunks, which the engine hands
 * straight to a native <a download>. Afterwards the whole database is deleted: the
 * staging copy is not left behind next to the file the user just saved.
 */

const DB_NAME = "fastlock-transfer";
const DB_VERSION = 1;
const STORE = "chunks";

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE)) {
        // Keyed by "<transferId>:<paddedIndex>" so a range scan returns chunks in
        // order without an index and without sorting a million keys in memory.
        db.createObjectStore(STORE);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB unavailable"));
    request.onblocked = () => reject(new Error("IndexedDB is blocked by another tab"));
  });
}

function done(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error("IndexedDB write failed"));
    tx.onabort = () => reject(tx.error ?? new Error("IndexedDB write aborted"));
  });
}

/** Zero-padded so lexicographic key order is numeric order, up to ~10 billion chunks. */
function keyFor(transferId: string, index: number): string {
  return `${transferId}:${String(index).padStart(10, "0")}`;
}

/**
 * Batched writes.
 *
 * One IndexedDB transaction per 16 KB chunk would spend more time in transaction
 * bookkeeping than in the transfer; a 50 GB file is 3.2 million chunks. Instead
 * chunks accumulate in a small buffer and are committed together, which is both far
 * faster and gentler on flash storage.
 */
export class ChunkStore {
  private db: IDBDatabase | null = null;
  private pending: { key: string; value: ArrayBuffer }[] = [];
  private pendingBytes = 0;
  private count = 0;

  /** Commit threshold. Big enough to amortise the transaction, small enough to hold. */
  private static readonly FLUSH_BYTES = 4 * 1024 * 1024;

  constructor(private readonly transferId: string) {}

  async init(): Promise<void> {
    this.db = await open();
    // A previous, abandoned attempt at the same link must not blend into this one.
    await this.clear();
  }

  private handle(): IDBDatabase {
    if (!this.db) throw new Error("ChunkStore.init() was not awaited");
    return this.db;
  }

  /** Stages one chunk. Resolves once it is safely in the buffer or on disk. */
  async put(index: number, chunk: ArrayBuffer): Promise<void> {
    this.pending.push({ key: keyFor(this.transferId, index), value: chunk });
    this.pendingBytes += chunk.byteLength;
    this.count = Math.max(this.count, index + 1);
    if (this.pendingBytes >= ChunkStore.FLUSH_BYTES) await this.flush();
  }

  async flush(): Promise<void> {
    if (this.pending.length === 0) return;
    const batch = this.pending;
    this.pending = [];
    this.pendingBytes = 0;

    const tx = this.handle().transaction(STORE, "readwrite");
    const store = tx.objectStore(STORE);
    for (const item of batch) store.put(item.value, item.key);
    await done(tx);
  }

  /**
   * Assembles the staged chunks into one Blob.
   *
   * The chunks are read back in key order and handed to the Blob constructor as a
   * list. The browser is free to keep that backed by disk rather than by RAM, which is
   * what makes a file larger than memory possible at all.
   */
  async assemble(type: string): Promise<Blob> {
    await this.flush();

    const parts: ArrayBuffer[] = [];
    const tx = this.handle().transaction(STORE, "readonly");
    const store = tx.objectStore(STORE);
    const range = IDBKeyRange.bound(`${this.transferId}:`, `${this.transferId}:￿`);

    await new Promise<void>((resolve, reject) => {
      const cursor = store.openCursor(range);
      cursor.onsuccess = () => {
        const handle = cursor.result;
        if (!handle) {
          resolve();
          return;
        }
        parts.push(handle.value as ArrayBuffer);
        handle.continue();
      };
      cursor.onerror = () => reject(cursor.error ?? new Error("IndexedDB read failed"));
    });

    return new Blob(parts, type ? { type } : undefined);
  }

  /** Removes this transfer's chunks, leaving the database itself in place. */
  async clear(): Promise<void> {
    this.pending = [];
    this.pendingBytes = 0;
    const tx = this.handle().transaction(STORE, "readwrite");
    const store = tx.objectStore(STORE);
    const range = IDBKeyRange.bound(`${this.transferId}:`, `${this.transferId}:￿`);
    store.delete(range);
    await done(tx);
  }

  close(): void {
    this.db?.close();
    this.db = null;
  }

  /**
   * Deletes the entire staging database.
   *
   * Called once the file is saved. Clearing the keys would be enough for correctness,
   * but not for the promise this product makes: after a transfer there should be no
   * second copy of the bytes anywhere on the machine except the file the user chose.
   */
  async destroy(): Promise<void> {
    this.close();
    await new Promise<void>((resolve) => {
      const request = indexedDB.deleteDatabase(DB_NAME);
      request.onsuccess = () => resolve();
      // Best effort: a failure here must never block handing over the file.
      request.onerror = () => resolve();
      request.onblocked = () => resolve();
    });
  }
}

/** Wipes the staging database outright, whatever is in it. */
export async function wipeChunkStore(): Promise<void> {
  await new Promise<void>((resolve) => {
    const request = indexedDB.deleteDatabase(DB_NAME);
    request.onsuccess = () => resolve();
    request.onerror = () => resolve();
    request.onblocked = () => resolve();
  });
}
