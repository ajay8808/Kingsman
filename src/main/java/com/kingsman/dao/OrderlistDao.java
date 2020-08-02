package com.kingsman.dao;

import java.util.Map;

import com.kingsman.vo.OrderlistVO;

public interface OrderlistDao {
	void create(OrderlistVO orderlist);
	void read(Map map);
	void readAll(Map map);
	void delete(int onum);
}
