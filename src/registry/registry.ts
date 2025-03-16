import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  const nodeRegistry: { nodeId: number; pubKey: string }[] = [];

  _registry.get("/status", (req: Request, res: Response) => {
    res.send("live");
  });

  _registry.post("/registerNode", (req: Request, res: Response) => {
    const { nodeId, pubKey } = req.body as RegisterNodeBody;
    if (nodeId === undefined || !pubKey) {
      return res.status(400).json({ error: "Missing nodeId or pubKey" });
    }
    const existingIndex = nodeRegistry.findIndex((node) => node.nodeId === nodeId);
    if (existingIndex >= 0) {
      // Update the public key if node already exists.
      nodeRegistry[existingIndex].pubKey = pubKey;
    } else {
      nodeRegistry.push({ nodeId, pubKey });
    }
    return res.json({ success: true });
  });

  _registry.get("/getNodeRegistry", (req: Request, res: Response) => {
    res.json({ nodes: nodeRegistry });
  });

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}
