export const PORT = parseInt(process.env.PORT || "4000", 10);
export const TOKEN_EXPIRY_SECONDS = parseInt(process.env.TOKEN_EXPIRY_SECONDS || "3600", 10);
export const DB_PATH = process.env.DB_PATH || "./ego.db";
