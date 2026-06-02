from dataclasses import dataclass


DECRYPT_RECOVERY_LABEL = "Use Recovery Phrase (standard/decoy only)"
INSPECT_RECOVERY_LABEL = "Use Recovery Phrase (standard/decoy only)"


@dataclass(frozen=True)
class RecoveryDialogCopy:
    title: str
    heading: str
    description: str
    checkbox_text: str


def get_recovery_dialog_copy(hidden_mode: bool) -> RecoveryDialogCopy:
    """
    Return recovery phrase dialog text without importing or instantiating GUI
    widgets.

    Hidden vault mode uses the normal recovery envelope only for the visible
    decoy vault. Hidden payload recovery is deliberately not implemented here.
    """
    if hidden_mode:
        return RecoveryDialogCopy(
            title="Decoy Recovery Phrase",
            heading="Your Decoy Recovery Phrase",
            description=(
                "Write this down and keep it safe. This phrase recovers only the "
                "decoy/visible content. It cannot recover hidden files. Hidden "
                "files require the hidden password; if that password is lost, "
                "hidden data is permanently unrecoverable."
            ),
            checkbox_text=(
                "I understand this phrase recovers only the decoy content, and "
                "hidden data is unrecoverable without the hidden password."
            ),
        )

    return RecoveryDialogCopy(
        title="Recovery Phrase",
        heading="Your Recovery Phrase",
        description=(
            "Write this down and keep it safe. It recovers this vault if the "
            "password is lost and will never be shown again."
        ),
        checkbox_text="I have securely saved this 24-word recovery phrase.",
    )
