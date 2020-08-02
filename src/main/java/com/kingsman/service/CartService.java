package com.kingsman.service;

import java.util.Map;

import com.kingsman.vo.CartVO;

public interface CartService {
	void insertCart(CartVO cart); //(member) 장바구니담기
//	void selectCart(Map map); // 
	void selectAllCarts(Map map); // (member) 장바구니전체보기
//	void updateCart(CartVO Cart); // 
	void deleteCart(int cnum); // (member) 장바구니 아이템 삭제
}
