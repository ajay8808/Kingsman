package com.kingsman.dao;

import java.util.Map;

import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.kingsman.vo.MemberVO;

@Repository("memberDao")
public class MemberDaoImpl implements MemberDao {

	@Autowired
	private SqlSession sqlSession;
	
	@Override
	public void create(MemberVO member) {
		this.sqlSession.insert("memberInsert", member);
	}

	@Override
	public void readAll(Map map) {
		this.sqlSession.selectList("memberSelectAll", map);
	}

	@Override
	public void delete(String memail) {
		this.sqlSession.delete("memberDelete", memail);
	}

	@Override
	public void read(Map map) {
		this.sqlSession.selectOne("memberSelect", map);
	}

	@Override
	public void update(MemberVO member) {
		this.sqlSession.update("memberUpdate", member);		
	}

}
