/**
 * Icon generation script.
 * Converts extension-icon.svg → extension-icon.png (128x128) for VS Code Marketplace.
 *
 * Usage:
 *   npm run generate-icons
 *
 * Requires: npm install --save-dev sharp
 */

const fs = require('fs');
const path = require('path');

async function generateIcons() {
  let sharp;
  try {
    sharp = require('sharp');
  } catch {
    console.error('Error: "sharp" is not installed. Run: npm install --save-dev sharp');
    process.exit(1);
  }

  const iconsDir = path.join(__dirname, '..', 'media', 'icons');
  const svgPath = path.join(iconsDir, 'extension-icon.svg');
  const pngPath = path.join(iconsDir, 'extension-icon.png');

  if (!fs.existsSync(svgPath)) {
    console.error(`SVG not found: ${svgPath}`);
    process.exit(1);
  }

  const svgBuffer = fs.readFileSync(svgPath);

  await sharp(svgBuffer)
    .resize(128, 128)
    .png()
    .toFile(pngPath);

  console.log(`✅ Generated: ${pngPath} (128x128)`);
}

generateIcons().catch(err => {
  console.error('Icon generation failed:', err);
  process.exit(1);
});
