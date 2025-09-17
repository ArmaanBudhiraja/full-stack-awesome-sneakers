// src/utils/imageLoader.js
const images = import.meta.glob('../images/*', { eager: true });

export const getImage = (imagePath) => {
  const formattedPath = imagePath.replace('src', '..');
  
  // ✅ Add this console log
  console.log('Trying to find image at path:', formattedPath);
  console.log('Available images:', Object.keys(images));

  return images[formattedPath]?.default || null;
};