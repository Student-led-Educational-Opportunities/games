#!/usr/bin/env node

import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";

const CHUNK_SIZE_BYTES = 20 * 1024 * 1024;
const MAX_CHUNK_ID = 0xffff;
const DEFAULT_KEY = 0xa5c3f17d;

function printUsage() {
  console.log(`
Usage:
  node chunker.js unmerge <inputFile> <outDir> <gameIdHex4>
  node chunker.js merge <chunksDir> <outputFile> [gameIdHex4]
  node chunker.js name <gameIdHex4> <chunkIdHex4>
  node chunker.js decode <chunkFileName>
`);
}

function toHex4(value) {
  return (value & 0xffff).toString(16).padStart(4, "0");
}

function toHex8(value) {
  return (value >>> 0).toString(16).padStart(8, "0");
}

function parseHex4(input, name) {
  if (!/^[0-9a-fA-F]{4}$/.test(input)) {
    throw new Error(`${name} must be exactly 4 hex digits`);
  }
  return parseInt(input, 16) & 0xffff;
}

function getKey() {
  const envKey = process.env.CHUNK_NAME_KEY;
  if (!envKey) {
    return DEFAULT_KEY;
  }
  if (!/^[0-9a-fA-F]{8}$/.test(envKey)) {
    throw new Error("CHUNK_NAME_KEY must be exactly 8 hex digits");
  }
  return parseInt(envKey, 16) >>> 0;
}

function rotl32(x, bits) {
  return ((x << bits) | (x >>> (32 - bits))) >>> 0;
}

function roundFunction(right16, subKey) {
  let x = (right16 ^ (subKey & 0xffff)) >>> 0;
  x ^= x >>> 7;
  x = Math.imul(x, 0x45d9f3b) >>> 0;
  x ^= x >>> 11;
  return x & 0xffff;
}

function encrypt32(value, key) {
  let left = (value >>> 16) & 0xffff;
  let right = value & 0xffff;

  for (let i = 0; i < 8; i += 1) {
    const subKey = (rotl32(key, (i * 5) % 32) ^ Math.imul(0x9e3779b9, i + 1)) >>> 0;
    const nextLeft = right;
    const nextRight = (left ^ roundFunction(right, subKey)) & 0xffff;
    left = nextLeft;
    right = nextRight;
  }

  return (((left << 16) >>> 0) | right) >>> 0;
}

function decrypt32(value, key) {
  let left = (value >>> 16) & 0xffff;
  let right = value & 0xffff;

  for (let i = 7; i >= 0; i -= 1) {
    const subKey = (rotl32(key, (i * 5) % 32) ^ Math.imul(0x9e3779b9, i + 1)) >>> 0;
    const prevRight = left;
    const prevLeft = (right ^ roundFunction(prevRight, subKey)) & 0xffff;
    left = prevLeft;
    right = prevRight;
  }

  return (((left << 16) >>> 0) | right) >>> 0;
}

function encodeChunkName(gameId, chunkId, key) {
  const packed = (((gameId & 0xffff) << 16) | (chunkId & 0xffff)) >>> 0;
  const obfuscated = encrypt32(packed, key);
  return `${toHex8(obfuscated)}.dat`;
}

function decodeChunkName(fileName, key) {
  const baseName = path.basename(fileName);
  if (!/^[0-9a-fA-F]{8}\.dat$/.test(baseName)) {
    throw new Error("chunk file name must look like 8hex.dat");
  }

  const obfuscated = parseInt(baseName.slice(0, 8), 16) >>> 0;
  const packed = decrypt32(obfuscated, key);
  return {
    gameId: (packed >>> 16) & 0xffff,
    chunkId: packed & 0xffff,
  };
}

async function unmergeFile(inputFile, outDir, gameIdHex4, key) {
  const gameId = parseHex4(gameIdHex4, "gameId");
  const stat = await fsp.stat(inputFile);

  await fsp.mkdir(outDir, { recursive: true });

  const fd = await fsp.open(inputFile, "r");
  let chunkCount = 0;
  let offset = 0;

  try {
    while (offset < stat.size) {
      if (chunkCount > MAX_CHUNK_ID) {
        throw new Error("too many chunks for 4-digit chunk IDs (max ffff)");
      }

      const bytesToRead = Math.min(CHUNK_SIZE_BYTES, stat.size - offset);
      const buffer = Buffer.allocUnsafe(bytesToRead);
      const { bytesRead } = await fd.read(buffer, 0, bytesToRead, offset);

      if (bytesRead === 0) {
        break;
      }

      const chunkBuffer = bytesRead === buffer.length ? buffer : buffer.subarray(0, bytesRead);
      const chunkFileName = encodeChunkName(gameId, chunkCount, key);
      const chunkPath = path.join(outDir, chunkFileName);

      await fsp.writeFile(chunkPath, chunkBuffer);

      chunkCount += 1;
      offset += bytesRead;
    }
  } finally {
    await fd.close();
  }

  console.log(`Wrote ${chunkCount} chunk(s) to ${outDir}`);
}

function appendFileToStream(filePath, outStream) {
  return new Promise((resolve, reject) => {
    const inStream = fs.createReadStream(filePath);
    inStream.on("error", reject);
    outStream.on("error", reject);
    inStream.on("end", resolve);
    inStream.pipe(outStream, { end: false });
  });
}

async function mergeFiles(chunksDir, outputFile, gameIdHex4, key) {
  const requestedGameId = gameIdHex4 ? parseHex4(gameIdHex4, "gameId") : null;
  const dirEntries = await fsp.readdir(chunksDir, { withFileTypes: true });

  const decodedChunks = [];

  for (const entry of dirEntries) {
    if (!entry.isFile()) {
      continue;
    }
    if (!entry.name.toLowerCase().endsWith(".dat")) {
      continue;
    }

    let decoded;
    try {
      decoded = decodeChunkName(entry.name, key);
    } catch {
      continue;
    }

    if (requestedGameId !== null && decoded.gameId !== requestedGameId) {
      continue;
    }

    decodedChunks.push({
      filePath: path.join(chunksDir, entry.name),
      fileName: entry.name,
      gameId: decoded.gameId,
      chunkId: decoded.chunkId,
    });
  }

  if (decodedChunks.length === 0) {
    throw new Error("no valid chunk files found for the requested game ID");
  }

  const uniqueGameIds = [...new Set(decodedChunks.map((chunk) => chunk.gameId))];
  if (requestedGameId === null && uniqueGameIds.length > 1) {
    throw new Error(
      `multiple game IDs found (${uniqueGameIds.map(toHex4).join(", ")}); pass a gameIdHex4 to merge one game`
    );
  }

  const mergeGameId = requestedGameId !== null ? requestedGameId : uniqueGameIds[0];
  const chunksToMerge = decodedChunks
    .filter((chunk) => chunk.gameId === mergeGameId)
    .sort((a, b) => a.chunkId - b.chunkId);

  for (let i = 1; i < chunksToMerge.length; i += 1) {
    if (chunksToMerge[i - 1].chunkId === chunksToMerge[i].chunkId) {
      throw new Error(`duplicate chunk ID ${toHex4(chunksToMerge[i].chunkId)} detected`);
    }
  }

  const expectedFirst = chunksToMerge[0].chunkId;
  if (expectedFirst !== 0) {
    console.warn(`warning: first chunk starts at ${toHex4(expectedFirst)} instead of 0000`);
  }

  for (let i = 1; i < chunksToMerge.length; i += 1) {
    const prev = chunksToMerge[i - 1].chunkId;
    const curr = chunksToMerge[i].chunkId;
    if (curr !== prev + 1) {
      console.warn(`warning: missing chunk between ${toHex4(prev)} and ${toHex4(curr)}`);
    }
  }

  await fsp.mkdir(path.dirname(outputFile), { recursive: true });

  await new Promise(async (resolve, reject) => {
    const outStream = fs.createWriteStream(outputFile);
    outStream.on("error", reject);

    try {
      for (const chunk of chunksToMerge) {
        await appendFileToStream(chunk.filePath, outStream);
      }
      outStream.end(resolve);
    } catch (error) {
      outStream.destroy();
      reject(error);
    }
  });

  console.log(
    `Merged ${chunksToMerge.length} chunk(s) for game ${toHex4(mergeGameId)} into ${outputFile}`
  );
}

async function main() {
  const key = getKey();
  const [, , command, ...args] = process.argv;

  if (!command || command === "-h" || command === "--help") {
    printUsage();
    return;
  }

  if (command === "unmerge") {
    if (args.length !== 3) {
      throw new Error("unmerge expects: <inputFile> <outDir> <gameIdHex4>");
    }
    await unmergeFile(args[0], args[1], args[2], key);
    return;
  }

  if (command === "merge") {
    if (args.length < 2 || args.length > 3) {
      throw new Error("merge expects: <chunksDir> <outputFile> [gameIdHex4]");
    }
    await mergeFiles(args[0], args[1], args[2], key);
    return;
  }

  if (command === "decode") {
    if (args.length !== 1) {
      throw new Error("decode expects: <chunkFileName>");
    }
    const decoded = decodeChunkName(args[0], key);
    console.log(`gameId=${toHex4(decoded.gameId)} chunkId=${toHex4(decoded.chunkId)}`);
    return;
  }

  if (command === "name") {
    if (args.length !== 2) {
      throw new Error("name expects: <gameIdHex4> <chunkIdHex4>");
    }
    const gameId = parseHex4(args[0], "gameId");
    const chunkId = parseHex4(args[1], "chunkId");
    console.log(encodeChunkName(gameId, chunkId, key));
    return;
  }

  throw new Error(`unknown command: ${command}`);
}

main().catch((error) => {
  console.error(`Error: ${error.message}`);
  process.exit(1);
});
