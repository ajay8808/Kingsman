package com.kingsman.main;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.kingsman.service.MemberService;
import com.kingsman.vo.MemberVO;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@CrossOrigin(origins = "*")
@RestController("memberController")
public class MemberController {

	@Autowired
	private MemberService memberService;

	@PostMapping("/member")
	public Map<String, Object> register(@RequestBody MemberVO member) {
		log.info("REGISTER MEMBER : {}", member);
		this.memberService.insertMember(member);
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("code", "success");
		return map;
	}

	@GetMapping("/member")
	public Map<String, Object> listAll() {
		Map<String, Object> map = new HashMap<String, Object>();
		this.memberService.selectAllMembers(map);
		List<MemberVO> list = (List<MemberVO>) map.get("memberResults");
		map.put("code", "success");
		map.put("memberResults", list);
		return map;
	}

	@GetMapping("/member/{memail}")
	public Map<String, Object> list(@PathVariable String memail) {
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("memail", memail);
		this.memberService.selectMember(map);
		List<MemberVO> list = (List<MemberVO>) map.get("memberResult");
		MemberVO member = null;
		if(list.size() >0)
			member = list.get(0);
//		map.remove("memail");
		map.remove("memberResult");
		map.put("code", "success");
		ProductController.memail = memail;
		map.put("memberResult", member);

		return map;
	}

	@DeleteMapping("/member/{memail}")
	public Map<String, Object> delete(@PathVariable String memail) {
		Map<String, Object> map = new HashMap<String, Object>();
		this.memberService.deleteMember(memail);
		map.put("code", "success");
		return map;
	}

	@PutMapping("/member")
	public Map<String, Object> update(@RequestBody MemberVO member) {
		Map<String, Object> map = new HashMap<String, Object>();
		log.info("" + member);
		this.memberService.updateMember(member);

		map.put("code", "success");
		map.put("memberResult", member);
		return map;
	}

}