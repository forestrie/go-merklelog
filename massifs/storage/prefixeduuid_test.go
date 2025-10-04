package storage

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func TestLogIDFromPrefixedUUID(t *testing.T) {

	mklogid := func(uuidstr string) LogID {
		uuid := uuid.MustParse(uuidstr)
		return LogID(uuid[:])
	}
	type args struct {
		prefix      string
		storagePath string
	}
	tests := []struct {
		name string
		args args
		want LogID
	}{
		{
			name: "valid prefix and path, uuid mid string",
			args: args{
				prefix:      "tenant/",
				storagePath: "v1/mmrs/tenant/01947000-3456-780f-bfa9-29881e3bac88/0/massifs/00000000000000000001.log",
			},
			want: mklogid("01947000-3456-780f-bfa9-29881e3bac88"),
		},

		{
			name: "valid prefix and path, uuid end of string",
			args: args{
				prefix:      "tenant/",
				storagePath: "v1/mmrs/tenant/01947000-3456-780f-bfa9-29881e3bac88",
			},
			want: mklogid("01947000-3456-780f-bfa9-29881e3bac88"),
		},

		{
			name: "valid prefix and path, exact match",
			args: args{
				prefix:      "tenant/",
				storagePath: "tenant/01947000-3456-780f-bfa9-29881e3bac88",
			},
			want: mklogid("01947000-3456-780f-bfa9-29881e3bac88"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParsePrefixedLogID(tt.args.prefix, tt.args.storagePath); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LogIDFromPrefixedUUID() = %v, want %v", got, tt.want)
			}
		})
	}
}
