use super::{conversation::ConversationStore, decryption::DecryptionService, reassembly::ReassemblyService};

#[derive(Debug, Default)]
pub struct ParserRuntime {
    pub conversations: ConversationStore,
    pub reassembly: ReassemblyService,
    pub decryption: DecryptionService,
}
