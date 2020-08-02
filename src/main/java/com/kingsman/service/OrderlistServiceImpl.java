package com.kingsman.service;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.kingsman.dao.OrderlistDao;
import com.kingsman.vo.OrderlistVO;

@Service("orderListService")
public class OrderlistServiceImpl implements OrderlistService {

	@Autowired
	private OrderlistDao orderListDao;
	
	@Override
	public void insertOrderlist(OrderlistVO orderlist) {
		this.orderListDao.create(orderlist);
	}

	@Override
	public void selectOrderlist(Map map) {
		this.orderListDao.read(map);

	}

	@Override
	public void selectAllOrderlists(Map map) {
		this.orderListDao.readAll(map);

	}


	@Override
	public void deleteOrderlist(int onum) {
		this.orderListDao.delete(onum); 
		
	}

}
