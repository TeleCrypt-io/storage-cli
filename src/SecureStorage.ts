import { MatrixClient } from "matrix-js-sdk";
import { encryptAttachment, decryptAttachment } from "matrix-encrypt-attachment";

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

export class SecureStorage {
  constructor(private client: MatrixClient) {}

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
      info as Parameters<typeof decryptAttachment>[1],
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
