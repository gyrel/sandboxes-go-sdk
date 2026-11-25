package sandboxes

import localv1 "github.com/gyrel/sandboxes-api/gen/go/sandboxes/local/v1"

func validateSkillsOptions(skills *SkillsOptions) error {
	if skills == nil {
		return nil
	}
	switch skills.Mode {
	case SkillsOff:
		if skills.StorePath == "" {
			return nil
		}
	case SkillsReadOnly, SkillsReadWrite:
		if skills.StorePath != "" {
			return nil
		}
	}
	return &Error{Code: errorCodeInvalidArgument, Message: "invalid shared skills mode or store path"}
}

func toProtoSkills(skills *SkillsOptions) *localv1.SkillsOptions {
	if skills == nil {
		return nil
	}
	var mode localv1.SkillsMode
	switch skills.Mode {
	case SkillsOff:
		mode = localv1.SkillsMode_SKILLS_MODE_OFF
	case SkillsReadOnly:
		mode = localv1.SkillsMode_SKILLS_MODE_READONLY
	case SkillsReadWrite:
		mode = localv1.SkillsMode_SKILLS_MODE_READWRITE
	}
	return &localv1.SkillsOptions{Mode: mode, StorePath: skills.StorePath}
}

func fromProtoSkills(skills *localv1.SkillsOptions) *SkillsOptions {
	if skills == nil {
		return nil
	}
	var mode SkillsMode
	switch skills.GetMode() {
	case localv1.SkillsMode_SKILLS_MODE_OFF:
		mode = SkillsOff
	case localv1.SkillsMode_SKILLS_MODE_READONLY:
		mode = SkillsReadOnly
	case localv1.SkillsMode_SKILLS_MODE_READWRITE:
		mode = SkillsReadWrite
	}
	return &SkillsOptions{Mode: mode, StorePath: skills.GetStorePath()}
}
