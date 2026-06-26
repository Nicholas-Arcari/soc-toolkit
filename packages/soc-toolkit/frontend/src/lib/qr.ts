import jsQR from "jsqr";

import { urlRiskFlags } from "./url";

export type QrKind = "url" | "wifi" | "email" | "tel" | "sms" | "geo" | "text";

export interface QrAnalysis {
  payload: string;
  kind: QrKind;
  flags: string[];
}

/** Classify a decoded QR payload and surface "quishing" risk flags. */
export function analyzeQrPayload(payload: string): QrAnalysis {
  const lower = payload.toLowerCase();
  const flags: string[] = [];
  let kind: QrKind = "text";

  if (/^https?:\/\//i.test(payload)) kind = "url";
  else if (lower.startsWith("wifi:")) kind = "wifi";
  else if (lower.startsWith("mailto:")) kind = "email";
  else if (lower.startsWith("tel:")) kind = "tel";
  else if (lower.startsWith("smsto:") || lower.startsWith("sms:")) kind = "sms";
  else if (lower.startsWith("geo:")) kind = "geo";

  if (kind === "url") {
    flags.push(...urlRiskFlags(payload));
  } else if (kind === "wifi") {
    flags.push("Wi-Fi join code — connecting may expose you to a rogue network");
  }

  return { payload, kind, flags };
}

/** Decode the first QR code in an image File (browser only). */
export async function decodeQrFromImageFile(file: File): Promise<string | null> {
  const objectUrl = URL.createObjectURL(file);
  try {
    const image = await loadImage(objectUrl);
    const canvas = document.createElement("canvas");
    canvas.width = image.naturalWidth;
    canvas.height = image.naturalHeight;
    const ctx = canvas.getContext("2d");
    if (!ctx || canvas.width === 0 || canvas.height === 0) return null;
    ctx.drawImage(image, 0, 0);
    const { data, width, height } = ctx.getImageData(
      0,
      0,
      canvas.width,
      canvas.height,
    );
    const code = jsQR(data, width, height);
    return code?.data ?? null;
  } finally {
    URL.revokeObjectURL(objectUrl);
  }
}

function loadImage(src: string): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const image = new Image();
    image.onload = () => resolve(image);
    image.onerror = () => reject(new Error("could not load image"));
    image.src = src;
  });
}
