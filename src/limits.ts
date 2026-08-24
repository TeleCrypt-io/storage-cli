/**
 * Consumer-side byte ceilings. Media is deliberately separate from private
 * profile/snapshot state: changing one must not silently enlarge the other.
 */
export const MAX_PRIVATE_FILE_BYTES = 64 * 1024 * 1024;
export const MAX_MEDIA_FILE_BYTES = 128 * 1024 * 1024;
