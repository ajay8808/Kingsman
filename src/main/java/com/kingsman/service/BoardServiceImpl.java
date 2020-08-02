package com.kingsman.service;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.kingsman.dao.BoardDao;
import com.kingsman.vo.BoardVO;

@Service("boardService")
public class BoardServiceImpl implements BoardService {
	
	@Autowired
	private BoardDao boardDao;

	@Override
	public void insertBoard(BoardVO board) {
		this.boardDao.create(board);
	}

	@Override
	public void selectAllBoards(Map map) {
	this.boardDao.readAll(map);

	}

	@Override
	public void deleteBoard(int bnum) {
		this.boardDao.delete(bnum);

	}

}
