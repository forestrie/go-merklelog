package watcher

import (
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/datatrails/go-datatrails-merklelog/massifs/storage"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testmkmassfpath(uuidstr string, i uint32) string {
	return fmt.Sprintf("v1/mmrs/tenant/%s/0/massifs/%020d.log", uuidstr, i)
}
func testmksealpath(uuidstr string, i uint32) string {
	return fmt.Sprintf("v1/mmrs/tenant/%s/0/massifseals/%020d.sth", uuidstr, i)
}
func testmklogid(uuidstr string) storage.LogID {
	uuid := uuid.MustParse(uuidstr)
	return storage.LogID(uuid[:])
}

func testpath2logid(storagePath string) storage.LogID {
	return storage.ParsePrefixedLogID("tenant/", storagePath)
}

func mkcollator(t *testing.T, paths []string) LogTailCollator {
	lc := NewLogTailCollator(testpath2logid, storage.ObjectIndexFromPath)

	for _, path := range paths {
		err := lc.CollatePath(path, "")
		require.NoError(t, err)
	}
	return lc
}

// Test_LatestSealsAndMassifs tests the basic ability to list discovered latest massif and seal.
func Test_LatestSealsAndMassifs(t *testing.T) {

	suuida := "01947000-3456-780f-bfa9-29881e3bac88"
	suuidb := "112758ce-a8cb-4924-8df8-fcba1e31f8b0"
	suuidc := "84e0e9e9-d479-4d4e-9e8c-afc19a8fc185"
	uuida := uuid.MustParse(suuida)
	uuidb := uuid.MustParse(suuidb)
	uuidc := uuid.MustParse(suuidc)
	logida := storage.LogID(uuida[:])
	logidb := storage.LogID(uuidb[:])
	logidc := storage.LogID(uuidc[:])

	type args struct {
		collator LogTailCollator
	}
	tests := []struct {
		name       string
		args       args
		tenants    []string
		massifLogs []string
		sealLogs   []string
	}{
		{
			name: "two massifs, one seal",
			args: args{
				mkcollator(t, []string{
					testmkmassfpath(suuida, 0),
					testmksealpath(suuidb, 0),
					testmkmassfpath(suuidc, 1),
				}),
			},
			massifLogs: []string{string(logida), string(logidc)},
			sealLogs:   []string{string(logidb)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.args.collator.MassifLogs()
			slices.Sort(got)
			if !reflect.DeepEqual(got, tt.massifLogs) {
				t.Errorf("expected massif logs: %x, got: %x", tt.massifLogs, got)
			}
			got = tt.args.collator.SealedLogs()
			slices.Sort(got)
			if !reflect.DeepEqual(got, tt.sealLogs) {
				t.Errorf("expected sealed logs: %x, got: %x", tt.sealLogs, got)
			}
		})
	}
}

func Test_CollatePath(t *testing.T) {

	uuida := "84e0e9e9-aaaa-4d4e-9e8c-afc19a8fc185"
	logida := testmklogid(uuida)
	uuidb := "112758ce-a8cb-4924-8df8-fcba1e31f8b0"
	logidb := testmklogid(uuidb)

	type fields struct {
		massifs map[string]*LogTail
		seals   map[string]*LogTail
	}
	type args struct {
		page []string
	}

	tests := []struct {
		name        string
		fields      fields
		args        args
		wantMassifs []*LogTail
		wantSeals   []*LogTail
		wantErr     bool
	}{
		{
			name: "singletone massif",
			fields: fields{
				make(map[string]*LogTail),
				make(map[string]*LogTail),
			},
			args: args{
				[]string{testmkmassfpath(uuida, 2)},
			},
			wantMassifs: []*LogTail{{LogID: logida, Number: 2}},
			wantSeals:   nil,
			wantErr:     false,
		},
		{
			name: "two massifs, one tenant, ascending",
			fields: fields{
				make(map[string]*LogTail),
				make(map[string]*LogTail),
			},
			args: args{
				[]string{
					testmkmassfpath(uuida, 1),
					testmkmassfpath(uuida, 2),
				},
			},
			wantMassifs: []*LogTail{{LogID: logida, Number: 2}},
			wantSeals:   nil,
			wantErr:     false,
		},
		{
			name: "two massifs, one tenant, descending",
			fields: fields{
				make(map[string]*LogTail),
				make(map[string]*LogTail),
			},
			args: args{
				[]string{
					testmkmassfpath(uuida, 2),
					testmkmassfpath(uuida, 1),
				},
			},
			wantMassifs: []*LogTail{{LogID: logida, Number: 2}},
			wantSeals:   nil,
			wantErr:     false,
		},

		{
			name: "two massifs, two tenants, descending",
			fields: fields{
				make(map[string]*LogTail),
				make(map[string]*LogTail),
			},
			args: args{
				[]string{
					testmkmassfpath(uuidb, 2),
					testmkmassfpath(uuida, 3),
					testmkmassfpath(uuida, 1),
				},
			},
			wantMassifs: []*LogTail{
				{LogID: logidb, Number: 2},
				{LogID: logida, Number: 3},
			},
			wantSeals: nil,
			wantErr:   false,
		},

		{
			name: "two massifs, one seal, two tenants, descending",
			fields: fields{
				make(map[string]*LogTail),
				make(map[string]*LogTail),
			},
			args: args{
				[]string{
					testmkmassfpath(uuida, 2),
					testmkmassfpath(uuidb, 3),
					testmksealpath(uuida, 2),
					testmkmassfpath(uuida, 1),
				},
			},
			wantMassifs: []*LogTail{
				{LogID: logida, Number: 2},
				{LogID: logidb, Number: 3},
			},
			wantSeals: []*LogTail{
				{LogID: logida, Number: 2},
			},

			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &LogTailCollator{
				Path2LogID:       testpath2logid,
				Path2ObjectIndex: storage.ObjectIndexFromPath,
				Massifs:          tt.fields.massifs,
				Seals:            tt.fields.seals,
			}

			var lastErr error
			for _, path := range tt.args.page {
				lastErr = c.CollatePath(path, "")
				if lastErr != nil {
					break
				}
			}
			if (lastErr != nil) != tt.wantErr {
				t.Errorf("LogTailCollator.CollatePath() error = %v, wantErr %v", lastErr, tt.wantErr)
				return
			}

			if tt.wantMassifs != nil {
				for _, want := range tt.wantMassifs {
					lt, ok := c.Massifs[string(want.LogID)]
					assert.Equal(t, ok, true, "%s expected in the collated tenants missing. %d")
					if want.OType != storage.ObjectUndefined {
						assert.Equal(t, lt.OType, want.OType)
					}
					if want.Path != "" {
						assert.Equal(t, lt.Path, want.Path)
					}
					assert.Equal(t, lt.Number, want.Number)
				}
			}
			if tt.wantSeals != nil {
				for _, want := range tt.wantSeals {
					lt, ok := c.Seals[string(want.LogID)]
					assert.Equal(t, ok, true, "%s expected in the collated tenants missing. %d")
					if want.OType != storage.ObjectUndefined {
						assert.Equal(t, lt.OType, want.OType)
					}
					if want.Path != "" {
						assert.Equal(t, lt.Path, want.Path)
					}
					assert.Equal(t, lt.Number, want.Number)
				}
			}
		})
	}
}

func Test_sortMapOfLogTails(t *testing.T) {
	type args struct {
		m map[string]*LogTail
	}

	mkmap := func(keys ...string) map[string]*LogTail {
		m := map[string]*LogTail{}
		for i, k := range keys {
			m[k] = &LogTail{Path: fmt.Sprintf("%d", i)}
		}
		return m
	}

	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "happy case",
			args: args{
				m: mkmap("bbbb", "aaaa"),
			},
			want: []string{"aaaa", "bbbb"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sortMapOfLogTails(tt.args.m); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("sortMapOfLogTails() = %v, want %v", got, tt.want)
			}
		})
	}
}
