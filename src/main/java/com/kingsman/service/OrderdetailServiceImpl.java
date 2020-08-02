package com.kingsman.service;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.kingsman.dao.OrderdetailDao;
import com.kingsman.vo.OrderdetailVO;

@Service("orderDetailService")
public class OrderdetailServiceImpl implements OrderdetailService {

	@Autowired
	private OrderdetailDao orderDetailDao;
	
	@Override
	public void selectOrderdetail(Map map) {
	this.orderDetailDao.read(map);  

	}

	@Override
	public void insertOrderdetail(OrderdetailVO detail) {
		this.orderDetailDao.create(detail);  
		
	}

}
