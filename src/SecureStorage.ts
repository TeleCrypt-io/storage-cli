import { MatrixClient } from "matrix-js-sdk";
import { MSC3089TreeSpace } from "matrix-js-sdk/src/models/MSC3089TreeSpace";

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
}

export type { MSC3089TreeSpace };
