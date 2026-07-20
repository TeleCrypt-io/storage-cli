import { MatrixClient } from "matrix-js-sdk";
import { MSC3089TreeSpace } from "matrix-js-sdk/src/models/MSC3089TreeSpace";
import { MSC3089Branch } from "matrix-js-sdk/src/models/MSC3089Branch";
import type { IEncryptedFile } from "matrix-encrypt-attachment";
import { encryptAttachment, decryptAttachment } from "matrix-encrypt-attachment";

export class SecureStorage {
  constructor(private client: MatrixClient) {}

  async createTree(name: string): Promise<MSC3089TreeSpace> {
    return this.client.unstableCreateFileTree(name);
  }

  async listTrees(): Promise<MSC3089TreeSpace[]> {
    const rooms = this.client.getRooms();
    const trees: MSC3089TreeSpace[] = [];
    for (const room of rooms) {
      const tree = this.client.unstableGetFileTreeSpace(room.roomId);
      if (tree) {
        trees.push(tree);
      }
    }
    return trees;
  }

  getTree(roomId: string): MSC3089TreeSpace | null {
    return this.client.unstableGetFileTreeSpace(roomId);
  }

  async uploadFile(
    tree: MSC3089TreeSpace,
    name: string,
    data: ArrayBuffer,
    mimetype: string,
  ): Promise<string> {
    const encrypted = await encryptAttachment(data);
    const { event_id } = await tree.createFile(
      name,
      Buffer.from(encrypted.data),
      encrypted.info,
      { info: { mimetype, size: data.byteLength } },
    );
    return event_id;
  }

  async downloadFile(
    branch: MSC3089Branch,
  ): Promise<{ data: ArrayBuffer; mimetype: string }> {
    const { info } = await branch.getFileInfo();
    const mxcUrl = info.url;
    const url = this.client.mxcUrlToHttp(
      mxcUrl,
      undefined,
      undefined,
      undefined,
      false,
      true,
      true,
    );
    if (!url) throw new Error("failed to build media URL");

    const res = await fetch(url, {
      headers: {
        Authorization: `Bearer ${this.client.getAccessToken()}`,
      },
    });
    if (!res.ok) {
      throw new Error(`media download failed: ${res.status}`);
    }
    const ciphertext = await res.arrayBuffer();
    const data = await decryptAttachment(ciphertext, info);
    const eventContent = (await branch.getFileEvent()).getContent() as Record<
      string,
      unknown
    >;
    const infoBlock = eventContent["info"] as Record<string, unknown> | undefined;
    const mimetype =
      typeof infoBlock?.["mimetype"] === "string"
        ? infoBlock["mimetype"]
        : "application/octet-stream";
    return { data, mimetype };
  }
}

export type { MSC3089TreeSpace, MSC3089Branch };
