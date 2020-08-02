package com.kingsman.dao;

import java.util.Map;

import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.kingsman.vo.ProductVO;

@Repository("productDao")
public class ProductDaoImpl implements ProductDao {
	@Autowired
	private SqlSession sqlSession;

	@Override
	public void read(Map map) {
		this.sqlSession.selectList("productSelect", map);
	}
	
	@Override
	public void readOne(Map map) {
		this.sqlSession.selectList("productSelectOne", map);
	}

	@Override
	public void readAll(Map map) {
		this.sqlSession.selectList("productSelectAll", map);

	}

	@Override
	public void update(ProductVO product) {
		this.sqlSession.update("productUpdate", product);

	}


}
