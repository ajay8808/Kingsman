package com.kingsman.dao;

import java.util.Map;

import com.kingsman.vo.OrderdetailVO;

public interface OrderdetailDao {

	void read(Map map);
	void create(OrderdetailVO detail);

}
