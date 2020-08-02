package com.kingsman.dao;

import java.util.Map;

import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.kingsman.vo.OrderdetailVO;

@Repository("orderDetailDao")
public class OrderdetailDaoImpl implements OrderdetailDao {
	@Autowired
	private SqlSession sqlSession;

	@Override
	public void read(Map map) {
		this.sqlSession.selectList("selectDetail", map);
	}

	@Override
	public void create(OrderdetailVO detail) {
		this.sqlSession.insert("insertDetail", detail);
	}

}
