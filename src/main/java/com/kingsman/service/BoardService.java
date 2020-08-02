package com.kingsman.service;

import java.util.Map;

import com.kingsman.vo.BoardVO;

public interface BoardService {
	void insertBoard(BoardVO board);  //댓글작성
//	void selectBoard(Map map);  
	void selectAllBoards(Map map); //댓글 전체 보기만 
//	void updateBoard(BoardVO board);  
	void deleteBoard(int bnum); //(member, admin)댓글 삭제
}
