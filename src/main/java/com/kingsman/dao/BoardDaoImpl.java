package com.kingsman.dao;

import java.util.Map;

import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.kingsman.vo.BoardVO;

@Repository("boardDao")
public class BoardDaoImpl implements BoardDao {
	@Autowired
	private SqlSession sqlSession;

	@Override
	public void create(BoardVO board) {
		this.sqlSession.insert("boardInsert", board);

	}

	@Override
	public void readAll(Map map) {
		this.sqlSession.selectList("boardSelectAll" ,map);

	}

	@Override
	public void delete(int bnum) {
		this.sqlSession.delete("boardDelete" , bnum);

	}

}
