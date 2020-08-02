package com.kingsman.dao;

import java.util.Map;

import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.kingsman.vo.OrderlistVO;

@Repository("orderListDao")
public class OrderlistDaoImpl implements OrderlistDao {
	@Autowired
	private SqlSession sqlSession;

	@Override
	public void create(OrderlistVO orderlist) {
		this.sqlSession.insert("insert", orderlist);

	}

	@Override
	public void read(Map map) {
		this.sqlSession.selectOne("select", map);
		
	}

	
	@Override
	public void readAll(Map map) {
		this.sqlSession.selectList("selectAll", map);
	}


	@Override
	public void delete(int onum) {
		this.sqlSession.delete("delete", onum);
	}

}
