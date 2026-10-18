package configlink

import "testing"

func TestRoundTrip(t *testing.T) {
	in := Config{
		Name:       "user1",
		Zone:       "t.example.com",
		PSK:        "deadbeef",
		Token:      "abc123",
		Candidates: "2.188.21.0/24, 178.22.122.100",
	}
	link := Encode(in)
	if link[:len(Scheme)] != Scheme {
		t.Fatalf("missing scheme: %q", link)
	}
	out, err := Decode(link)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round trip mismatch:\n in=%+v\nout=%+v", in, out)
	}
}

func TestDecodeErrors(t *testing.T) {
	if _, err := Decode("https://example.com"); err == nil {
		t.Error("expected error for non-dnsvpn link")
	}
	if _, err := Decode("dnsvpn://not!base64"); err == nil {
		t.Error("expected error for bad base64")
	}
	// valid base64 but missing required fields
	if _, err := Decode(Encode(Config{Name: "x"})); err == nil {
		t.Error("expected error for link missing zone/psk")
	}
}

func TestDecodeTolerant(t *testing.T) {
	link := Encode(Config{Zone: "z", PSK: "p"}) + "/"
	if _, err := Decode(" " + link + " "); err != nil {
		t.Errorf("should tolerate trailing slash/space: %v", err)
	}
}
