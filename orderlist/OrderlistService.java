package com.kingsman.service;

import java.util.Map;

import com.kingsman.vo.OrderlistVO;

//주문리스트
public interface OrderlistService {
	void insertOrderlist(OrderlistVO orderlist); //(member) 주문리스트
	void selectOrderlist(Map map); // (member) 주문상세보기
	void selectAllOrderlists(Map map); // (member) 주문전체보기
	void deleteOrderlist(int onum); // (member) 주문삭제

}
