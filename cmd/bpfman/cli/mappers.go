package cli

import (
	"reflect"

	"github.com/alecthomas/kong"
)

// programIDMapper creates a Kong mapper for ProgramID.
func programIDMapper() kong.MapperFunc {
	return func(ctx *kong.DecodeContext, target reflect.Value) error {
		var s string
		if err := ctx.Scan.PopValueInto("program-id", &s); err != nil {
			return err
		}
		id, err := ParseProgramID(s)
		if err != nil {
			return err
		}
		target.Set(reflect.ValueOf(id))
		return nil
	}
}

// linkIDMapper creates a Kong mapper for LinkID.
func linkIDMapper() kong.MapperFunc {
	return func(ctx *kong.DecodeContext, target reflect.Value) error {
		var s string
		if err := ctx.Scan.PopValueInto("link-id", &s); err != nil {
			return err
		}
		id, err := ParseLinkID(s)
		if err != nil {
			return err
		}
		target.Set(reflect.ValueOf(id))
		return nil
	}
}

// linkUUIDMapper creates a Kong mapper for LinkUUID.
func linkUUIDMapper() kong.MapperFunc {
	return func(ctx *kong.DecodeContext, target reflect.Value) error {
		var s string
		if err := ctx.Scan.PopValueInto("link-uuid", &s); err != nil {
			return err
		}
		u, err := ParseLinkUUID(s)
		if err != nil {
			return err
		}
		target.Set(reflect.ValueOf(u))
		return nil
	}
}

// keyValueMapper creates a Kong mapper for KeyValue.
func keyValueMapper() kong.MapperFunc {
	return func(ctx *kong.DecodeContext, target reflect.Value) error {
		var s string
		if err := ctx.Scan.PopValueInto("key=value", &s); err != nil {
			return err
		}
		kv, err := ParseKeyValue(s)
		if err != nil {
			return err
		}
		target.Set(reflect.ValueOf(kv))
		return nil
	}
}

// globalDataMapper creates a Kong mapper for GlobalData.
func globalDataMapper() kong.MapperFunc {
	return func(ctx *kong.DecodeContext, target reflect.Value) error {
		var s string
		if err := ctx.Scan.PopValueInto("name=hex", &s); err != nil {
			return err
		}
		gd, err := ParseGlobalData(s)
		if err != nil {
			return err
		}
		target.Set(reflect.ValueOf(gd))
		return nil
	}
}

// objectPathMapper creates a Kong mapper for ObjectPath.
func objectPathMapper() kong.MapperFunc {
	return func(ctx *kong.DecodeContext, target reflect.Value) error {
		var s string
		if err := ctx.Scan.PopValueInto("path", &s); err != nil {
			return err
		}
		op, err := ParseObjectPath(s)
		if err != nil {
			return err
		}
		target.Set(reflect.ValueOf(op))
		return nil
	}
}

// dbPathMapper creates a Kong mapper for DBPath.
func dbPathMapper() kong.MapperFunc {
	return func(ctx *kong.DecodeContext, target reflect.Value) error {
		var s string
		if err := ctx.Scan.PopValueInto("path", &s); err != nil {
			return err
		}
		dp, err := ParseDBPath(s)
		if err != nil {
			return err
		}
		target.Set(reflect.ValueOf(dp))
		return nil
	}
}

// programSpecMapper creates a Kong mapper for ProgramSpec.
func programSpecMapper() kong.MapperFunc {
	return func(ctx *kong.DecodeContext, target reflect.Value) error {
		var s string
		if err := ctx.Scan.PopValueInto("type:name", &s); err != nil {
			return err
		}
		ps, err := ParseProgramSpec(s)
		if err != nil {
			return err
		}
		target.Set(reflect.ValueOf(ps))
		return nil
	}
}

// imagePullPolicyMapper creates a Kong mapper for ImagePullPolicy.
func imagePullPolicyMapper() kong.MapperFunc {
	return func(ctx *kong.DecodeContext, target reflect.Value) error {
		var s string
		if err := ctx.Scan.PopValueInto("policy", &s); err != nil {
			return err
		}
		pp, err := ParseImagePullPolicy(s)
		if err != nil {
			return err
		}
		target.Set(reflect.ValueOf(pp))
		return nil
	}
}
