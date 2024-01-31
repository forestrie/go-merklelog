package mmr

import "testing"

func TestStub(t *testing.T) {
	tests := []struct {
		name string
		want int
	}{
		{
			name: "positive",
			want: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Stub(); got != test.want {
				t.Errorf("Stub() = %v, want %v", got, test.want)
			}
		})
	}
}
