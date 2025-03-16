import express from "express";
import bodyParser from "body-parser";
import axios from "axios";
import crypto from "crypto";
import { BASE_USER_PORT, REGISTRY_PORT, BASE_ONION_ROUTER_PORT } from "../config";
import { rsaEncrypt, symEncrypt, createRandomSymmetricKey } from "../crypto";

export async function user(userId: number) {
  const userServer = express();
  userServer.use(express.json());
  userServer.use(bodyParser.json());

  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;
  let lastCircuit: number[] | null = null;

  // /status endpoint.
  userServer.get("/status", (req, res) => {
    res.send("live");
  });

  // GET routes for test verification.
  userServer.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });
  userServer.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });
  userServer.get("/getLastCircuit", (req, res) => {
    res.json({ result: lastCircuit });
  });

  // POST /message: When a message is delivered to this user.
  userServer.post("/message", (req, res) => {
    const { message } = req.body;
    lastReceivedMessage = message;
    res.send("success");
  });
  
  // POST /sendMessage: Send a message through a randomly built 3-node circuit.
  userServer.post("/sendMessage", async (req, res) => {
    try {
      const { message, destinationUserId } = req.body;
      lastSentMessage = message;

      // Retrieve node registry.
      const registryRes = await axios.get(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
      const nodes: { nodeId: number; pubKey: string }[] = registryRes.data.nodes;
      if (nodes.length < 3) {
        res.status(500).send("Not enough nodes in registry");
        return;
      }

      // Randomly select 3 nodes.
      const shuffled = nodes.sort(() => 0.5 - Math.random());
      const circuitNodes = shuffled.slice(0, 3);
      lastCircuit = circuitNodes.map((node) => node.nodeId);

      let payload = message;

      // For each node in the circuit (from last to first), add an encryption layer.
      for (let i = circuitNodes.length - 1; i >= 0; i--) {
        let nextHop: number;
        if (i === circuitNodes.length - 1) {
          nextHop = BASE_USER_PORT + destinationUserId;
        } else {
          nextHop = BASE_ONION_ROUTER_PORT + circuitNodes[i + 1].nodeId;
        }
        const nextHopEncoded = nextHop.toString().padStart(10, "0");
        const dataToEncrypt = nextHopEncoded + payload;

        // Create a symmetric key (returns a CryptoKey).
        const symmetricKey = await createRandomSymmetricKey();
        // Export symmetric key as raw bytes and get its base64 string (for RSA encryption).
        const symmetricKeyRaw = Buffer.from(
          await crypto.webcrypto.subtle.exportKey("raw", symmetricKey)
        );
        const symmetricKeyBase64 = symmetricKeyRaw.toString("base64");

        // Use the correct argument order for symEncrypt: (symmetricKey, data).
        const encryptedPayload = await symEncrypt(symmetricKey, dataToEncrypt);

        // Import node's public key (from base64) into a CryptoKey.
        const importedPublicKey = await crypto.webcrypto.subtle.importKey(
          "spki",
          Buffer.from(circuitNodes[i].pubKey, "base64"),
          { name: "RSA-OAEP", hash: "SHA-256" },
          true,
          ["encrypt"]
        );
        // Encrypt the symmetric key (as its base64 string) using RSA.
        const encryptedKeyBuffer = await rsaEncrypt(symmetricKeyBase64, circuitNodes[i].pubKey);
        payload = encryptedKeyBuffer + "||" + encryptedPayload;
      }

      // Send the fully layered payload to the entry node.
      const entryNodePort = BASE_ONION_ROUTER_PORT + circuitNodes[0].nodeId;
      await axios.post(`http://localhost:${entryNodePort}/message`, { message: payload });

      res.json({ result: "message sent" });
    } catch (error) {
      console.error("Error in /sendMessage:", error);
      res.status(500).send("Error sending message");
    }
  });

  const server = userServer.listen(BASE_USER_PORT + userId, () => {
    console.log(`User ${userId} is listening on port ${BASE_USER_PORT + userId}`);
  });
  return server;
}
