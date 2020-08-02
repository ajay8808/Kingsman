package com.kingsman.service;

import java.util.Map;

import com.kingsman.vo.MemberVO;

public interface MemberService {
	void insertMember(MemberVO member); //회원가입
	void selectMember(Map map); // 회원조회(마이페이지)
	void selectAllMembers(Map map); // (관리자만) 회원전체조회 
	void updateMember(MemberVO member); // 나의 정보 수정
	void deleteMember(String userid); // (관리자만) 회원삭제
}


