import { webcrypto } from "crypto";

// #############
// ### Utils ###
// #############

// Function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

// Function to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  var buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// ################
// ### RSA keys ###
// ################

// Generates a pair of private / public RSA keys
type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
};
export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  // TODO implement this function using the crypto package to generate a public and private RSA key pair.
  //      the public key should be used for encryption and the private key for decryption. Make sure the
  //      keys are extractable.

  const keyPair = await webcrypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]), // 65537
      hash: "SHA-256",
    },
    true, // Keys are extractable
    ["encrypt", "decrypt"]
  );

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
  };
}

// Export a crypto public key to a base64 string format
export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  // TODO implement this function to return a base64 string version of a public key

  const exported = await webcrypto.subtle.exportKey("spki", key);
  return arrayBufferToBase64(exported);
}

// Export a crypto private key to a base64 string format
export async function exportPrvKey(
  key: webcrypto.CryptoKey | null
): Promise<string | null> {
  // TODO implement this function to return a base64 string version of a private key

  if (!key) return null;
  const exported = await webcrypto.subtle.exportKey("pkcs8", key);
  return arrayBufferToBase64(exported);
}

// Import a base64 string public key to its native format
export async function importPubKey(strKey: string): Promise<webcrypto.CryptoKey> {
  // TODO implement this function to go back from the result of the exportPubKey function to it's native crypto key object

  const buffer = base64ToArrayBuffer(strKey);
  return webcrypto.subtle.importKey(
    "spki",
    buffer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["encrypt"]
  );
}

// Import a base64 string private key to its native format
export async function importPrvKey(strKey: string): Promise<webcrypto.CryptoKey> {
  // TODO implement this function to go back from the result of the exportPrvKey function to it's native crypto key object

  const buffer = base64ToArrayBuffer(strKey);
  return webcrypto.subtle.importKey(
    "pkcs8",
    buffer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["decrypt"]
  );
}

// Encrypt a message using an RSA public key
export async function rsaEncrypt(b64Data: string, strPublicKey: string): Promise<string> {
  // TODO implement this function to encrypt a base64 encoded message with a public key
  // tip: use the provided base64ToArrayBuffer function

  const publicKey = await importPubKey(strPublicKey);
  const encoded = new TextEncoder().encode(b64Data);
  const encrypted = await webcrypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    encoded
  );
  return arrayBufferToBase64(encrypted);
}

// Decrypts a message using an RSA private key
export async function rsaDecrypt(data: string, privateKey: webcrypto.CryptoKey): Promise<string> {
  // TODO implement this function to decrypt a base64 encoded message with a private key
  // tip: use the provided base64ToArrayBuffer function

  const encryptedBuffer = base64ToArrayBuffer(data);
  const decrypted = await webcrypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    encryptedBuffer
  );
  return new TextDecoder().decode(decrypted);
}

// ######################
// ### Symmetric keys ###
// ######################

// Generates a random symmetric key
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  // TODO implement this function using the crypto package to generate a symmetric key.
  //      the key should be used for both encryption and decryption. Make sure the
  //      keys are extractable.

  return webcrypto.subtle.generateKey(
    {
      name: "AES-CBC",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  )
}

// Export a crypto symmetric key to a base64 string format
export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  // TODO implement this function to return a base64 string version of a symmetric key

  const exported = await webcrypto.subtle.exportKey("raw", key);
  return arrayBufferToBase64(exported);
}

// Import a base64 string format to its crypto native format
export async function importSymKey(strKey: string): Promise<webcrypto.CryptoKey> {
  // TODO implement this function to go back from the result of the exportSymKey function to it's native crypto key object

  const buffer = base64ToArrayBuffer(strKey);
  return webcrypto.subtle.importKey(
    "raw",
    buffer,
    { name: "AES-CBC", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

// Encrypt a message using a symmetric key
export async function symEncrypt(key: webcrypto.CryptoKey, data: string): Promise<string> {
  // TODO implement this function to encrypt a base64 encoded message with a public key
  // tip: encode the data to a uin8array with TextEncoder

  const iv = webcrypto.getRandomValues(new Uint8Array(16)); // 16-byte IV
  const encodedData = new TextEncoder().encode(data);
  const encrypted = await webcrypto.subtle.encrypt(
    { name: "AES-CBC", iv },
    key,
    encodedData
  );
  return arrayBufferToBase64(iv) + ":" + arrayBufferToBase64(encrypted);
}

// Decrypt a message using a symmetric key
export async function symDecrypt(strKey: string, encryptedData: string): Promise<string> {
  // TODO implement this function to decrypt a base64 encoded message with a private key
  // tip: use the provided base64ToArrayBuffer function and use TextDecode to go back to a string format

  const [ivStr, dataStr] = encryptedData.split(":");
  const iv = base64ToArrayBuffer(ivStr);
  const buffer = base64ToArrayBuffer(dataStr);
  const key = await importSymKey(strKey);
  const decrypted = await webcrypto.subtle.decrypt(
    { name: "AES-CBC", iv: new Uint8Array(iv) },
    key,
    buffer
  );
  return new TextDecoder().decode(decrypted);
}
