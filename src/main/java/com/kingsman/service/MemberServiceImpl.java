package com.kingsman.service;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.kingsman.dao.MemberDao;
import com.kingsman.vo.MemberVO;

@Service("memberService")
public class MemberServiceImpl implements MemberService {

	@Autowired
	private MemberDao memberDao;
	
	@Override
	public void insertMember(MemberVO member) {
		this.memberDao.create(member);
	}

	@Override
	public void selectMember(Map map) {
		this.memberDao.read(map);
	}

	@Override
	public void selectAllMembers(Map map) {
		this.memberDao.readAll(map);
	}

	@Override
	public void updateMember(MemberVO member) {
		this.memberDao.update(member);
	}

	@Override
	public void deleteMember(String memail) {
		this.memberDao.delete(memail);
	}

}
