package com.kingsman.dao;

import java.util.Map;

import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.kingsman.vo.CartVO;
@Repository("cartDao")
public class CartDaoImpl implements CartDao {

	@Autowired
	private SqlSession sqlSession;
	
	@Override
	public void create(CartVO cart) {
		this.sqlSession.insert("cartInsert",cart);
	}


	@Override
	public void readAll(Map map) {
		this.sqlSession.selectList("cartSelectAll", map);

	}


	@Override
	public void delete(int cnum) {
		this.sqlSession.delete("cartDelete", cnum);
	}

}
