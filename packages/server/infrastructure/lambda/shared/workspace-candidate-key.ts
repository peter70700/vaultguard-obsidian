/** Candidate objects are outside legacy vault listings. Only a committed logical
 * file version may point here; its exact preparation/file-version IDs bind the key. */
export function workspaceCandidateKey(
  scope: { orgId: string; vaultId: string },
  preparationId: string,
  fileVersionId: string,
): string {
  if (
    ![scope.orgId, scope.vaultId, preparationId, fileVersionId].every((id) =>
      /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(id),
    ) ||
    !fileVersionId.startsWith("fver_")
  )
    throw new Error("Invalid candidate binding");
  return ["_vaultguard-apply", scope.orgId, scope.vaultId, preparationId, fileVersionId]
    .map((x) => Buffer.from(x).toString("base64url"))
    .join("/");
}
