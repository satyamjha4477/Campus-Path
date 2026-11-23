export const MAX_AVATAR_DATA_URL_LENGTH = 24000;
const TARGET_AVATAR_SIZE = 128;
const ALLOWED_AVATAR_MIMES = new Set(['image/jpeg', 'image/png', 'image/webp']);
const QUALITY_STEPS = [0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2];

function loadImageFromFile(file: File): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const objectUrl = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      URL.revokeObjectURL(objectUrl);
      resolve(img);
    };
    img.onerror = () => {
      URL.revokeObjectURL(objectUrl);
      reject(new Error('Could not decode the selected image file.'));
    };
    img.src = objectUrl;
  });
}

export async function processAvatarFile(file: File): Promise<string> {
  if (!ALLOWED_AVATAR_MIMES.has(file.type)) {
    throw new Error('Please choose a JPG, PNG, or WEBP image.');
  }

  const img = await loadImageFromFile(file);
  if (!img.naturalWidth || !img.naturalHeight) {
    throw new Error('Selected image has invalid dimensions.');
  }

  const side = Math.min(img.naturalWidth, img.naturalHeight);
  const sx = Math.floor((img.naturalWidth - side) / 2);
  const sy = Math.floor((img.naturalHeight - side) / 2);

  const canvas = document.createElement('canvas');
  canvas.width = TARGET_AVATAR_SIZE;
  canvas.height = TARGET_AVATAR_SIZE;
  const ctx = canvas.getContext('2d');
  if (!ctx) {
    throw new Error('Your browser could not process this image.');
  }

  ctx.imageSmoothingEnabled = true;
  ctx.imageSmoothingQuality = 'high';
  ctx.drawImage(img, sx, sy, side, side, 0, 0, TARGET_AVATAR_SIZE, TARGET_AVATAR_SIZE);

  // Try image/webp first (only if browser supports WebP encoding), then fall back to image/jpeg
  const webpProbe = canvas.toDataURL('image/webp', QUALITY_STEPS[0]);
  const supportsWebp = webpProbe.startsWith('data:image/webp;base64,');

  if (supportsWebp) {
    if (webpProbe.length < MAX_AVATAR_DATA_URL_LENGTH) {
      return webpProbe;
    }
    for (const q of QUALITY_STEPS.slice(1)) {
      const candidate = canvas.toDataURL('image/webp', q);
      if (
        candidate.startsWith('data:image/webp;base64,') &&
        candidate.length < MAX_AVATAR_DATA_URL_LENGTH
      ) {
        return candidate;
      }
    }
  }

  for (const q of QUALITY_STEPS) {
    const candidate = canvas.toDataURL('image/jpeg', q);
    if (
      candidate.startsWith('data:image/jpeg;base64,') &&
      candidate.length < MAX_AVATAR_DATA_URL_LENGTH
    ) {
      return candidate;
    }
  }

  throw new Error(
    'This image is still too large after compression. Please try a simpler or smaller photo.'
  );
}
