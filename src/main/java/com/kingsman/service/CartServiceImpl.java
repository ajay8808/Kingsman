package com.kingsman.service;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.kingsman.dao.CartDao;
import com.kingsman.vo.CartVO;

@Service("cartService")
public class CartServiceImpl implements CartService {
	@Autowired
	private CartDao cartDao;

	@Override
	public void insertCart(CartVO cart) {
		this.cartDao.create(cart);
	}

	@Override
	public void selectAllCarts(Map map) {
		this.cartDao.readAll(map);
	}

	@Override
	public void deleteCart(int cnum) {
		this.cartDao.delete(cnum);
	}

}
