package com.kingsman.oauth2.security;

import java.security.Principal;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
public class OAuth2Controller {

	/*
	 * @GetMapping({ "", "/" }) public String getAuthorizationMessage() { return
	 * "home.html"; }
	 */

	@GetMapping("/login")
	public String login() {
		return "main";
	}

	@GetMapping({ "/loginSuccess", "/hello" })
	public String loginSuccess(Principal principal, Model model) {
		return "verify.html";
	}

	@GetMapping("/username")
	@ResponseBody
	public String currentUserName(Principal principal) {
		return principal.getName();
	}

	@GetMapping("/loginFailure")
	public String loginFailure() {
		return "loginFailure";
	}
}