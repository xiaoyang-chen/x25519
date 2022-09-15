package x25519

import (
	"reflect"
	"testing"
)

func Test_ageX25519Wrap_GeneratePubKeyAndPrivateKey(t *testing.T) {
	type args struct {
		pubPrefix     string
		privatePrefix string
	}
	tests := []struct {
		name        string
		a           *ageX25519Wrap
		args        args
		wantPub     string
		wantPrivate string
		wantErr     bool
	}{
		{
			name: "edge-device-controller",
			a:    &ageX25519Wrap{},
			args: args{
				pubPrefix:     "edge-device-controller.pub-",
				privatePrefix: "edge-device-controller-",
			},
			wantPub:     "",
			wantPrivate: "",
			wantErr:     false,
		},
		{
			name: "empty prefix",
			a:    &ageX25519Wrap{},
			args: args{
				pubPrefix:     "",
				privatePrefix: "",
			},
			wantPub:     "",
			wantPrivate: "",
			wantErr:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &ageX25519Wrap{}
			gotPub, gotPrivate, err := a.GeneratePubKeyAndPrivateKey(tt.args.pubPrefix, tt.args.privatePrefix)
			if (err != nil) != tt.wantErr {
				t.Errorf("ageX25519Wrap.GeneratePubKeyAndPrivateKey() error = %+v, wantErr %v", err, tt.wantErr)
				return
			}
			t.Logf("ageX25519Wrap.GeneratePubKeyAndPrivateKey() gotPub = %v, want %v", gotPub, tt.wantPub)
			t.Logf("ageX25519Wrap.GeneratePubKeyAndPrivateKey() gotPrivate = %v, want %v", gotPrivate, tt.wantPrivate)
		})
	}
}

func Test_ageX25519Wrap_EncryptByPubKeyWithPrefix(t *testing.T) {
	type args struct {
		in        []byte
		publicKey string
		prefix    string
	}
	tests := []struct {
		name    string
		a       *ageX25519Wrap
		args    args
		wantOut []byte
		wantErr bool
	}{
		{
			name: "edge-device-controller",
			a:    &ageX25519Wrap{},
			args: args{
				in:        []byte("hello, world"),
				publicKey: "edge-device-controller.pub-1h8r5869agh9lxre6w5c24h3vf86tygfcvfhsy6l0u2d07r983ejsm99ur4",
				prefix:    "edge-device-controller.pub-",
			},
			wantOut: []byte{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &ageX25519Wrap{}
			gotOut, err := a.EncryptByPubKeyWithPrefix(tt.args.in, tt.args.publicKey, tt.args.prefix)
			if (err != nil) != tt.wantErr {
				t.Errorf("ageX25519Wrap.EncryptByPubKeyWithPrefix() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// gotOut of running first time is diff with output of running second time, in two outputs of running
			t.Logf("ageX25519Wrap.EncryptByPubKeyWithPrefix() = %q, want %q", gotOut, tt.wantOut)
		})
	}
}

func Test_ageX25519Wrap_DecryptByPrivateKeyWithPrefix(t *testing.T) {
	type args struct {
		in         []byte
		privateKey string
		prefix     string
	}
	tests := []struct {
		name    string
		a       *ageX25519Wrap
		args    args
		wantOut []byte
		wantErr bool
	}{
		{
			name: "edge-device-controller",
			a:    &ageX25519Wrap{},
			args: args{
				in:         []byte("age-encryption.org/v1\n-> X25519 3u929d1GSFKNiJ6u9ci3LV5vkxcoyCDMP3dh3U+OsTI\ny4C6M/Iu78kg+6EDeA7VnoA8VRm+dk1GPRbQ+FpxgD4\n--- SdZ3J3GcBBn8sdmH3U3N8eLZW+YVttBwYTsUDVROLWs\n\x8b\xc5\xfe\xe6zC\x8e\x81\xd2\xdfi\xb9|J\x0f\xfc\x10\xf6\xc8z؛ښs\x9c\x838\xec\xf7\x82\t\x9c\xd13g\t\x03\xe5YSO\xa0w"),
				privateKey: "EDGE-DEVICE-CONTROLLER-1FCS2CKCQTLXVAXLN99R70PQGRCRZHM0KR5JG92WXYXFFPEMPV3DSVVF5DX",
				prefix:     "edge-device-controller-",
			},
			wantOut: []byte("hello, world"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &ageX25519Wrap{}
			gotOut, err := a.DecryptByPrivateKeyWithPrefix(tt.args.in, tt.args.privateKey, tt.args.prefix)
			if (err != nil) != tt.wantErr {
				t.Errorf("ageX25519Wrap.DecryptByPrivateKeyWithPrefix() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotOut, tt.wantOut) {
				t.Errorf("ageX25519Wrap.DecryptByPrivateKeyWithPrefix() = %v, want %v", gotOut, tt.wantOut)
			}
		})
	}
}
