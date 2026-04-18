import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import path from 'path';

// Assuming you've compiled or are loading the proto dynamically
const PROTO_PATH = path.join(__dirname, '../../../ascp_integration/adapters/proto/ascp.proto');

const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true
});

const ascpProto = grpc.loadPackageDefinition(packageDefinition).ascp as any;

function main() {
    const client = new ascpProto.OrchestratorService(
        'localhost:50051',
        grpc.credentials.createInsecure() // use createSsl() for prod
    );

    const ctx = {
        agent_id: "ts-agent-1",
        framework: "langchainjs",
        workflow: "chat",
        history: [],
        evidence_ids: [],
        trust_vector: {},
        metadata: {}
    };

    client.BeginInvocation({
        version: "1.0",
        correlation_id: "req_xyz",
        invocation_context: ctx
    }, (error: any, response: any) => {
        if (error) {
            console.error("Error connecting to ASCP:", error);
            return;
        }
        console.log("Session Started:", response.session_id);
        console.log("Decision:", response.decision.status);
        
        // Next: check a tool call
        client.HookToolCall({
            version: "1.0",
            correlation_id: "req_xyz",
            tool_name: "fetch_user",
            tool_args: { fields: { user_id: { stringValue: "123" } } },
            invocation_context: ctx
        }, (err: any, res: any) => {
            if (err) {
               console.error("HookToolCall error:", err);
               return;
            }
            console.log("Tool Call Decision:", res.decision.status);
            console.log("Sanitized Args:", res.sanitized_args);
        });
    });
}

main();
