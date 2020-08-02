package com.kingsman.service;

import java.util.Map;

import com.kingsman.vo.OrderdetailVO;

public interface OrderdetailService {

	void selectOrderdetail(Map map); // 주문상세 1개만 보여줌
	void insertOrderdetail(OrderdetailVO detail); // 주문상세 1개만 보여줌
}
