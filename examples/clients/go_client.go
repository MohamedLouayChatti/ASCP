package main

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"

	// Replace with actual generated proto path
	pb "github.com/yourorg/ascp/adapters/proto"
)

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewOrchestratorServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	invokeCtx := &pb.InvocationContext{
		AgentId:   "go-agent-1",
		Framework: "custom-go",
		Workflow:  "batch-job",
	}

	// 1. Begin Invocation
	beginRes, err := c.BeginInvocation(ctx, &pb.BeginInvocationRequest{
		Version:           "1.0",
		CorrelationId:     "req_1",
		InvocationContext: invokeCtx,
	})
	if err != nil {
		log.Fatalf("could not begin invocation: %v", err)
	}
	log.Printf("Session ID: %s, Decision: %s", beginRes.GetSessionId(), beginRes.GetDecision().GetStatus())

	// 2. Output Hook
	outRes, err := c.HookAgentOutput(ctx, &pb.AgentOutputRequest{
		Version:           "1.0",
		CorrelationId:     "req_1",
		GeneratedText:     "Here is the final answer.",
		ContextDocs:       []string{"Doc 1"},
		InvocationContext: invokeCtx,
	})
	if err != nil {
		log.Fatalf("could not invoke hook output: %v", err)
	}
	log.Printf("Clean Text: %s, Decision: %s", outRes.GetCleanText(), outRes.GetDecision().GetStatus())
}
