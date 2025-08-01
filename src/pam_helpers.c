////
// PAM helpers
////

// I/O
static int converse(const pam_handle_t *pamh, int nargs, const struct pam_message **message, struct pam_response **response) {
	struct pam_conv *conv;

	int retval = pam_get_item(pamh, PAM_CONV, (const void**)&conv);
	if (retval == PAM_SUCCESS) {
		retval = conv->conv(nargs, message, response, conv->appdata_ptr);
	}

	return retval;
}


static int pamh_readline(const pam_handle_t *pamh, int visible, const char* str, char* *res) {
	// Prepare mesg structs
	const struct pam_message mesg[1] = {
		{ .msg_style = visible ? PAM_PROMPT_ECHO_ON : PAM_PROMPT_ECHO_OFF, .msg = str }
	};
	const struct pam_message *pmesg[1] = { &mesg[0] };

	struct pam_response *resp = NULL;
	int retval = converse(pamh, 1, pmesg, &resp);
	if (retval != PAM_SUCCESS || resp == NULL || resp[0].resp == NULL) {
		if (resp) free(resp);
		return PAM_CONV_ERR;
	}

	*res = resp[0].resp;  // Transfer ownership of the string only
	free(resp);           // Free the response array (but keep the string)
	return PAM_SUCCESS;
}

static int pamh_info(const pam_handle_t *pamh, const char* str) {
	// Prepare mesg structs
	const struct pam_message mesg[1] = {
		{ .msg_style = PAM_TEXT_INFO, .msg = str }
	};
	const struct pam_message *pmesg[1] = { &mesg[0] };

	// Display text
	return converse(pamh, 1, pmesg, NULL);
}

static int pamh_error(const pam_handle_t *pamh, const char* str) {
	const struct pam_message mesg[1] = {
		{ .msg_style = PAM_ERROR_MSG, .msg = str }
	};
	const struct pam_message *pmesg[1] = { &mesg[0] };

	// send error
	return converse(pamh, 1, pmesg, NULL);
}

// Items
#define PAM_LUA_PITYPE_STRING 1
#define PAM_LUA_PITYPE_CONV 2
#define PAM_LUA_PITYPE_FAIL_DELAY 3

static int pam_get_itype(const char* iname, int *type) {
	*type = PAM_LUA_PITYPE_STRING;
	if (strcmp(iname, "service"))
		return PAM_SERVICE;
	if (strcmp(iname, "user"))
		return PAM_USER;
	if (strcmp(iname, "user_prompt"))
		return PAM_USER_PROMPT;
	if (strcmp(iname, "tty"))
		return PAM_TTY;
	if (strcmp(iname, "ruser"))
		return PAM_RUSER;
	if (strcmp(iname, "rhost"))
		return PAM_RHOST;
	if (strcmp(iname, "authtok"))
		return PAM_AUTHTOK;
	if (strcmp(iname, "oldauthtok"))
		return PAM_OLDAUTHTOK;
	if (strcmp(iname, "conv")) {
		*type = PAM_LUA_PITYPE_CONV;
		return PAM_CONV;
	}

	// OS specific stuff
#ifdef __linux
	if (strcmp(iname, "authtok_type"))
		return PAM_AUTHTOK_TYPE;
	if (strcmp(iname, "fail_delay")) {
		*type = PAM_LUA_PITYPE_FAIL_DELAY;
		return PAM_FAIL_DELAY;
	}
	if (strcmp(iname, "xdisplay"))
		return PAM_XDISPLAY;
	if (strcmp(iname, "xauthdata"))
		return PAM_XAUTHDATA;
#endif
	return PAM_SYMBOL_ERR;
}
