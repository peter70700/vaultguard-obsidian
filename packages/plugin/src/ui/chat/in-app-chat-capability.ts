// Module-private authority shared only by VaultGuard's plugin entrypoint and
// built-in chat view. The Symbol is never stored on the public plugin instance,
// so another Obsidian plugin cannot call the trusted Local Mode lease/server
// methods merely by discovering their JavaScript method names.
export const IN_APP_CHAT_CAPABILITY: unique symbol = Symbol("vaultguard-in-app-chat");

export type InAppChatCapability = typeof IN_APP_CHAT_CAPABILITY;
