package server

import (
	"testing"
	"time"
)

func TestBrokerPublishesToSubscriber(t *testing.T) {
	events := newBroker()
	channel, cancel := events.subscribe()
	defer cancel()
	events.publish(`{"agent_id":"node-01"}`)
	select {
	case message := <-channel:
		if message != `{"agent_id":"node-01"}` {
			t.Fatalf("unexpected message: %s", message)
		}
	case <-time.After(time.Second):
		t.Fatal("event was not delivered")
	}
}
