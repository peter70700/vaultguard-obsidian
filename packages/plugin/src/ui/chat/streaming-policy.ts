/** Live token streaming is an explicit desktop-only enhancement. */
export function chatStreamingEnabled(preference: boolean, isMobileApp: boolean): boolean {
  return preference && !isMobileApp;
}
