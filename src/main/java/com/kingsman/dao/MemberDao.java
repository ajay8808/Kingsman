package com.kingsman.dao;

import java.util.Map;

import com.kingsman.vo.MemberVO;

public interface MemberDao {
	void create(MemberVO member);

	void read(Map map);

	void readAll(Map map);

	void update(MemberVO member);

	void delete(String memail);
}
