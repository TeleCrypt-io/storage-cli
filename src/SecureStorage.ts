import { ClientEvent, createClient, MatrixClient, SyncState } from "matrix-js-sdk";
import { encryptAttachment, decryptAttachment } from "matrix-encrypt-attachment";
import type { CryptoCallbacks } from "matrix-js-sdk/lib/crypto-api";
import { decodeRecoveryKey } from "matrix-js-sdk/lib/crypto-api/recovery-key";

export interface TreeSpace {
  readonly id: string;
  readonly room: { name: string };
  readonly isTopLevel: boolean;
  setName(name: string): Promise<void>;
  createDirectory(name: string): Promise<TreeSpace>;
  getDirectories(): TreeSpace[];
  getDirectory(roomId: string): TreeSpace | undefined;
  invite(userId: string, andSubspaces?: boolean): Promise<void>;
  delete(): Promise<void>;
  getOrder(): number;
  setOrder(index: number): Promise<void>;
  getPermissions(userId: string): string;
  setPermissions(userId: string, role: string): Promise<void>;
  getFile(fileEventId: string): FileBranch | null;
  listFiles(): FileBranch[];
  listAllFiles(): FileBranch[];
  createFile(
    name: string,
    encryptedContents: Buffer | ArrayBuffer | Uint8Array,
    info: Record<string, unknown>,
    additionalContent?: Record<string, unknown>,
  ): Promise<{ event_id: string }>;
}

export interface FileBranch {
  readonly id: string;
  readonly version: number;
  readonly isActive: boolean;
  getName(): string;
  setName(name: string): Promise<void>;
  delete(): Promise<void>;
  getFileInfo(): Promise<{
    info: Record<string, unknown>;
    httpUrl: string;
  }>;
  getFileEvent(): Promise<{ getContent: () => Record<string, unknown> }>;
  getVersionHistory(): Promise<FileBranch[]>;
  createNewVersion(
    name: string,
    encryptedContents: Buffer | ArrayBuffer | Uint8Array,
    info: Record<string, unknown>,
    additionalContent?: Record<string, unknown>,
  ): Promise<{ event_id: string }>;
}

export interface CreateSecureStorageOpts {
  /** Matrix homeserver base URL, e.g. "https://matrix.example.com". */
  baseUrl: string;
  userId: string;
  accessToken: string;
  deviceId: string;
  /**
   * Use a persistent crypto store (IndexedDB) so keys survive a restart on this
   * device. This is the default (`true`) — it is what makes both same-device
   * restart recovery and (via `keys.setupRecovery`/`restoreFromRecoveryKey`)
   * new-device recovery possible. Set explicitly to `false` to opt into an
   * in-memory, amnesiac store; this must be a deliberate choice, e.g. for a
   * short-lived process that should never persist secrets to disk.
   */
  persistentCryptoStore?: boolean;
  /**
   * Overrides the IndexedDB name prefix used for the crypto store. Defaults to
   * a value scoped to (userId, deviceId) so that multiple devices/users never
   * collide when they happen to share a single IndexedDB origin (e.g. in
   * Node/tests, where `fake-indexeddb` is process-global).
   */
  cryptoDatabasePrefix?: string;
  /** initialSyncLimit passed to startClient(); default 10. */
  initialSyncLimit?: number;
  /** How long to wait for the first sync before giving up; default 15000ms. */
  syncTimeoutMs?: number;
  /**
   * Optional platform-supplied crypto callbacks (e.g. to source the secret
   * storage key from an OS keychain instead of prompting). `keys.setupRecovery`
   * and `keys.restoreFromRecoveryKey` temporarily override
   * `getSecretStorageKey`/`cacheSecretStorageKey` on this object for the
   * duration of the call, then restore whatever was here before.
   */
  cryptoCallbacks?: CryptoCallbacks;
}

export class SecureStorage {
  constructor(private client: MatrixClient) {}

  /** The underlying matrix-js-sdk client (e.g. to stop it, or for advanced/interop use). */
  getClient(): MatrixClient {
    return this.client;
  }

  /**
   * Recommended entry point: builds the MatrixClient with a persistent crypto
   * store and the secret-storage callback wiring `keys.*` needs, starts the
   * client, waits for the first sync, and returns a ready SecureStorage.
   *
   * The plain constructor remains available for advanced callers who need to
   * build/configure the MatrixClient themselves; in that case `keys.*` only
   * works if the caller wires equivalent cryptoCallbacks onto the client at
   * construction time (see `cryptoCallbacks` above for why: matrix-js-sdk
   * captures a single callbacks object at MatrixClient construction, so it
   * must exist before `initRustCrypto` runs, not be added afterwards).
   */
  static async create(opts: CreateSecureStorageOpts): Promise<SecureStorage> {
    const client = createClient({
      baseUrl: opts.baseUrl,
      userId: opts.userId,
      accessToken: opts.accessToken,
      deviceId: opts.deviceId,
      cryptoCallbacks: opts.cryptoCallbacks ?? {},
    });

    const persistent = opts.persistentCryptoStore ?? true;
    await client.initRustCrypto({
      useIndexedDB: persistent,
      cryptoDatabasePrefix:
        opts.cryptoDatabasePrefix ?? `secure-storage::${opts.userId}::${opts.deviceId}`,
    });

    await client.startClient({ initialSyncLimit: opts.initialSyncLimit ?? 10 });

    await new Promise<void>((resolve, reject) => {
      const timeoutMs = opts.syncTimeoutMs ?? 15000;
      const timeout = setTimeout(
        () => reject(new Error("sync timeout")),
        timeoutMs,
      );
      client.once(ClientEvent.Sync, (state: SyncState) => {
        clearTimeout(timeout);
        if (state === SyncState.Prepared || state === SyncState.Syncing) {
          resolve();
        } else {
          reject(new Error(`unexpected sync state: ${state}`));
        }
      });
    });

    return new SecureStorage(client);
  }

  private requireCrypto() {
    const crypto = this.client.getCrypto();
    if (!crypto) {
      throw new Error(
        "SecureStorage: this client's crypto was never initialised (call client.initRustCrypto() first, or use SecureStorage.create())",
      );
    }
    return crypto;
  }

  /**
   * Temporarily wires `getSecretStorageKey`/`cacheSecretStorageKey` on the
   * client's cryptoCallbacks to hand back `privateKey`, runs `fn`, then
   * restores whatever callbacks were there before — regardless of success or
   * failure. Requires that the client was constructed with a cryptoCallbacks
   * object in the first place (see `create()`'s doc comment).
   */
  private async withSecretStorageKey<T>(
    privateKey: Uint8Array<ArrayBuffer>,
    fn: () => Promise<T>,
  ): Promise<T> {
    const callbacks = this.client.cryptoCallbacks;
    const prevGetKey = callbacks.getSecretStorageKey;
    const prevCache = callbacks.cacheSecretStorageKey;
    callbacks.getSecretStorageKey = async ({ keys }) => {
      const keyId = Object.keys(keys)[0];
      return [keyId, privateKey] as [string, Uint8Array<ArrayBuffer>];
    };
    callbacks.cacheSecretStorageKey = () => {};
    try {
      return await fn();
    } finally {
      callbacks.getSecretStorageKey = prevGetKey;
      callbacks.cacheSecretStorageKey = prevCache;
    }
  }

  /**
   * Bootstraps cross-signing and secret storage with a brand-new server-side
   * key backup, and returns the Recovery Key for the caller to show the user.
   * This is what makes `restoreFromRecoveryKey` on another device possible.
   */
  private async keysSetupRecovery(): Promise<{ recoveryKey: string }> {
    const crypto = this.requireCrypto();

    await crypto.bootstrapCrossSigning({
      // No existing verified device to interactively re-authenticate against
      // for this account, so there is nothing to feed into `makeRequest`;
      // matches the working pattern already proven in keys.test.ts.
      authUploadDeviceSigningKeys: async () => undefined,
    });

    const generated = await crypto.createRecoveryKeyFromPassphrase();
    if (!generated.encodedPrivateKey) {
      throw new Error(
        "setupRecovery: matrix-js-sdk did not return an encoded recovery key",
      );
    }

    await this.withSecretStorageKey(generated.privateKey, async () => {
      await crypto.bootstrapSecretStorage({
        setupNewSecretStorage: true,
        setupNewKeyBackup: true,
        createSecretStorageKey: async () => generated,
      });
      await crypto.checkKeyBackupAndEnable();
    });

    return { recoveryKey: generated.encodedPrivateKey };
  }

  /** Is there an active key backup and a ready secret storage right now? */
  private async keysIsRecoverySetup(): Promise<boolean> {
    const crypto = this.client.getCrypto();
    if (!crypto) return false;
    const [storageStatus, backupVersion] = await Promise.all([
      crypto.getSecretStorageStatus(),
      crypto.getActiveSessionBackupVersion(),
    ]);
    return storageStatus.ready && backupVersion !== null;
  }

  /**
   * On a new device: unlocks secret storage with the Recovery Key, loads the
   * key-backup decryption key out of secret storage, and restores the key
   * backup so previously-uploaded files become decryptable again.
   *
   * Throws a clear error (never silently "succeeds" with zero keys) if the
   * recovery key is malformed or does not unlock this account's secret
   * storage / key backup.
   */
  private async keysRestoreFromRecoveryKey(
    recoveryKey: string,
  ): Promise<{ imported: number; total: number }> {
    const crypto = this.requireCrypto();

    let privateKey: Uint8Array<ArrayBuffer>;
    try {
      privateKey = decodeRecoveryKey(recoveryKey);
    } catch (err) {
      throw new Error(
        `restoreFromRecoveryKey: not a valid recovery key (${(err as Error).message})`,
      );
    }

    return this.withSecretStorageKey(privateKey, async () => {
      try {
        await crypto.loadSessionBackupPrivateKeyFromSecretStorage();
      } catch (err) {
        throw new Error(
          `restoreFromRecoveryKey: recovery key did not unlock secret storage / key backup (${(err as Error).message})`,
        );
      }

      try {
        const result = await crypto.restoreKeyBackup();
        return { imported: result.imported, total: result.total };
      } catch (err) {
        throw new Error(
          `restoreFromRecoveryKey: failed to restore key backup (${(err as Error).message})`,
        );
      }
    });
  }

  /** Key-management API: setup, status, and restore for server-side Secure Backup. */
  get keys(): {
    setupRecovery: () => Promise<{ recoveryKey: string }>;
    isRecoverySetup: () => Promise<boolean>;
    restoreFromRecoveryKey: (
      recoveryKey: string,
    ) => Promise<{ imported: number; total: number }>;
  } {
    return {
      setupRecovery: () => this.keysSetupRecovery(),
      isRecoverySetup: () => this.keysIsRecoverySetup(),
      restoreFromRecoveryKey: (recoveryKey: string) =>
        this.keysRestoreFromRecoveryKey(recoveryKey),
    };
  }

  async createTree(name: string): Promise<TreeSpace> {
    return this.client.unstableCreateFileTree(name) as unknown as TreeSpace;
  }

  async listTrees(): Promise<TreeSpace[]> {
    const rooms = this.client.getRooms();
    const trees: TreeSpace[] = [];
    for (const room of rooms) {
      const tree = this.client.unstableGetFileTreeSpace(
        room.roomId,
      ) as unknown as TreeSpace | null;
      if (tree) {
        trees.push(tree);
      }
    }
    return trees;
  }

  getTree(roomId: string): TreeSpace | null {
    return this.client.unstableGetFileTreeSpace(
      roomId,
    ) as unknown as TreeSpace | null;
  }

  async uploadFile(
    tree: TreeSpace,
    name: string,
    data: ArrayBuffer,
    mimetype: string,
  ): Promise<string> {
    const encrypted = await encryptAttachment(data);
    const { event_id } = await tree.createFile(
      name,
      Buffer.from(encrypted.data),
      encrypted.info as unknown as Record<string, unknown>,
      { info: { mimetype, size: data.byteLength } },
    );
    return event_id;
  }

  async downloadFile(
    branch: FileBranch,
  ): Promise<{ data: ArrayBuffer; mimetype: string }> {
    const { info } = await branch.getFileInfo();
    const mxcUrl = info.url as string;
    const clientAny = this.client as unknown as {
      mxcUrlToHttp: (
        mxc: string,
        ...args: unknown[]
      ) => string | null;
      getAccessToken: () => string | null;
    };
    const downloadUrl = clientAny.mxcUrlToHttp(
      mxcUrl,
      undefined,
      undefined,
      undefined,
      false,
      true,
      true,
    );
    if (!downloadUrl) throw new Error("failed to build media URL");

    const res = await fetch(downloadUrl, {
      headers: {
        Authorization: `Bearer ${clientAny.getAccessToken()}`,
      },
    });
    if (!res.ok) {
      throw new Error(`media download failed: ${res.status}`);
    }
    const ciphertext = await res.arrayBuffer();
    const data = await decryptAttachment(
      ciphertext,
      info as unknown as Parameters<typeof decryptAttachment>[1],
    );
    const eventContent = (await branch.getFileEvent()).getContent();
    const infoBlock = eventContent["info"] as Record<string, unknown> | undefined;
    const mimetype =
      typeof infoBlock?.["mimetype"] === "string"
        ? infoBlock["mimetype"]
        : "application/octet-stream";
    return { data, mimetype };
  }
}
